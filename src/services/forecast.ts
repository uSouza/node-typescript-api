import _ from 'lodash';
import { StormGlass, ForecastPoint } from '@src/clients/stormGlass';
import { InternalError } from '@src/util/errors/internal-error';
import { Beach } from '@src/models/beach';
import logger from '@src/logger';
import { Rating } from './rating';

export interface TimeForecast {
  time: string;
  forecast: BeachForecast[];
}

export class ForecastProcessingInternalError extends InternalError {
  constructor(message: string) {
    super(`Unexpected error during the forecast processing: ${message}`);
  }
}

export interface BeachForecast extends Omit<Beach, 'user'>, ForecastPoint {}

export class Forecast {
  constructor(
    protected stormGlass = new StormGlass(),
    protected RatingService: typeof Rating = Rating
  ) {}

  public async processForecastForBeaches(
    beaches: Beach[]
  ): Promise<TimeForecast[]> {
    try {
      const beachForecast = await this.calculateRating(beaches);
      const timeForecast = this.mapForecastByTime(beachForecast);
      return timeForecast.map((t) => ({
        time: t.time,
        forecast: _.orderBy(t.forecast, ['rating'], ['desc']),
      }));
    } catch (error) {
      logger.error(error);
      throw new ForecastProcessingInternalError(error.message);
    }
  }

  private async calculateRating(beaches: Beach[]): Promise<BeachForecast[]> {
    const pointsWithCorrectSources: BeachForecast[] = [];
    logger.info(`Preparing the forecast for ${beaches.length} beaches`);
    for (const beach of beaches) {
      const rating = new this.RatingService(beach);
      const points = await this.stormGlass.fetchPoints(beach.lat, beach.lng);
      pointsWithCorrectSources.push(
        ...this.enrichedBeachData(points, beach, rating)
      );
    }
    return pointsWithCorrectSources;
  }

  private enrichedBeachData(
    points: ForecastPoint[],
    beach: Beach,
    rating: Rating
  ): BeachForecast[] {
    return points.map((point) => ({
      lat: beach.lat,
      lng: beach.lng,
      name: beach.name,
      position: beach.position,
      rating: rating.getRateForPoint(point),
      ...point,
    }));
  }

  private mapForecastByTime(forecast: BeachForecast[]): TimeForecast[] {
    return forecast.reduce(
      (
        forecastByTime: TimeForecast[],
        point: BeachForecast
      ): TimeForecast[] => {
        const timePointIdx = forecastByTime.findIndex(
          (f) => f.time === point.time
        );
        if (timePointIdx !== -1) {
          forecastByTime[timePointIdx].forecast.push(point);
          return forecastByTime;
        }
        forecastByTime.push({
          time: point.time,
          forecast: [point],
        });
        return forecastByTime;
      },
      []
    );
  }
}
